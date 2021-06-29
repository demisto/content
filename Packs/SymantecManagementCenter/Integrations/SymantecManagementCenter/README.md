<!-- HTML_DOC -->
<div class="cl-preview-section">
<p>Symantec Management Center provides a unified management environment for the Symantec Security Platform portfolio of products. Management Center brings Symantec’s network, security, and cloud technologies to you under a single umbrella making it easier to deploy, manage, and monitor your security environment.</p>
</div>
<div class="cl-preview-section">
<p>In Cortex XSOAR, the integration with Symantec MC allows viewing and managing devices and policies.<br> The integration was integrated and tested with version 2.2.1.1 of Symantec Management Center.</p>
</div>
<div class="cl-preview-section">
<h2 id="use-cases">Use Cases</h2>
</div>
<div class="cl-preview-section">
<ol>
<li>View information about devices in Symantec MC</li>
<li>View, create, update and delete policies in Symantec MC</li>
<li>Manage shared IP/category/URL lists in Symantec MC</li>
</ol>
</div>
<div class="cl-preview-section">
<h2 id="configure-symantec-management-center-on-demisto">Configure Symantec Management Center on Cortex XSOAR</h2>
</div>
<div class="cl-preview-section">
<p>In order to access the API, user credentials for Symantec Management Center are required.</p>
</div>
<div class="cl-preview-section">
<ol>
<li>Navigate to <strong>Settings</strong> &gt; <strong>Integrations</strong> &gt; <strong>Servers &amp; Services</strong>.</li>
<li>Search for Symantec Management Center.</li>
<li>Click <strong>Add instance</strong> to create and configure a new integration instance.
<ul>
<li>
<strong>Name</strong>: a textual name for the integration instance.</li>
<li><strong>Server URL (e.g.: https://192.168.0.1:8082)</strong></li>
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
<li><a href="#get-a-list-of-all-devices" target="_self">Get a list of all devices: symantec-mc-list-devices</a></li>
<li><a href="#get-device-information" target="_self">Get device information: symantec-mc-get-device</a></li>
<li><a href="#get-device-health-information" target="_self">Get device health information: symantec-mc-get-device-health</a></li>
<li><a href="#get-license-information-for-a-device" target="_self">Get license information for a device: symantec-mc-get-device-license</a></li>
<li><a href="#get-the-status-of-a-device" target="_self">Get the status of a device: symantec-mc-get-device-status</a></li>
<li><a href="#get-a-list-of-policies" target="_self">Get a list of policies: symantec-mc-list-policies</a></li>
<li><a href="#get-policy-information" target="_self">Get policy information: symantec-mc-get-policy</a></li>
<li><a href="#create-a-policy" target="_self">Create a policy: symantec-mc-create-policy</a></li>
<li><a href="#update-a-policy" target="_self">Update a policy: symantec-mc-update-policy</a></li>
<li><a href="#delete-a-policy" target="_self">Delete a policy: symantec-mc-delete-policy</a></li>
<li><a href="#get-a-list-of-tenants" target="_self">Get a list of tenants: symantec-mc-list-tenants</a></li>
<li><a href="#add-content-to-a-policy" target="_self">Add content to a policy: symantec-mc-add-policy-content</a></li>
<li><a href="#delete-policy-content" target="_self">Delete policy content: symantec-mc-delete-policy-content</a></li>
<li><a href="#update-policy-content" target="_self">Update policy content: symantec-mc-update-policy-content</a></li>
</ol>
</div>
<div class="cl-preview-section">
<h3 id="get-a-list-of-all-devices">1. Get a list of all devices</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Lists all devices in Symantec MC.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>symantec-mc-list-devices</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 151px;"><strong>Argument Name</strong></th>
<th style="width: 518px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 151px;">build</td>
<td style="width: 518px;">Filter the query filter parameter by the OS build number, for example: “GT 227900”.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 151px;">description</td>
<td style="width: 518px;">Filter the query filter parameter by description, for example: “CONTAINS” desc".</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 151px;">model</td>
<td style="width: 518px;">Filter the query filter parameter by model, for example: “EQ VSWG-SE”.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 151px;">name</td>
<td style="width: 518px;">Filter the query filter parameter by name, for example: “STARTSWITH CAS”.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 151px;">os_version</td>
<td style="width: 518px;">Filter the query filter parameter by OS version, for example: “LT 2.3”.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 151px;">platform</td>
<td style="width: 518px;">Filter the query filter parameter by platform, for example: “CONTAINS CAS”.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 151px;">type</td>
<td style="width: 518px;">Filter the query filter parameter by device type, for example: “cas”.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 151px;">limit</td>
<td style="width: 518px;">Maximum number of results to return.</td>
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
<th style="width: 370px;"><strong>Path</strong></th>
<th style="width: 79px;"><strong>Type</strong></th>
<th style="width: 291px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 370px;">SymantecMC.Device.UUID</td>
<td style="width: 79px;">String</td>
<td style="width: 291px;">Device UUID.</td>
</tr>
<tr>
<td style="width: 370px;">SymantecMC.Device.Name</td>
<td style="width: 79px;">String</td>
<td style="width: 291px;">Device name.</td>
</tr>
<tr>
<td style="width: 370px;">SymantecMC.Device.LastChanged</td>
<td style="width: 79px;">Date</td>
<td style="width: 291px;">Device last changed date.</td>
</tr>
<tr>
<td style="width: 370px;">SymantecMC.Device.Type</td>
<td style="width: 79px;">String</td>
<td style="width: 291px;">Device type.</td>
</tr>
<tr>
<td style="width: 370px;">SymantecMC.Device.Host</td>
<td style="width: 79px;">String</td>
<td style="width: 291px;">Device host address.</td>
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
<pre>symantec-mc-list-devices name="CONTAINS Blue Coat"</pre>
</div>
<div class="cl-preview-section">
<h5 id="context-example">Context Example</h5>
</div>
<div class="cl-preview-section">
<pre>{
    "SymantecMC.Device": [
        {
            "Host": "192.168.1.207", 
            "UUID": "C131C3D1-171B-4DA7-ADE2-AA736EA91540", 
            "Type": "sgos6x", 
            "Name": "192.168.1.207 - Blue Coat SG-VA Series", 
            "LastChanged": "2019-04-08T11:27:32"
        }
    ]
}
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<h3 id="symantec-management-center-devices">Symantec Management Center Devices</h3>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table border="2">
<thead>
<tr>
<th>UUID</th>
<th>Name</th>
<th>Last Changed</th>
<th>Host</th>
<th>Type</th>
</tr>
</thead>
<tbody>
<tr>
<td>C131C3D1-171B-4DA7-ADE2-AA736EA91540</td>
<td>192.168.1.207 - Blue Coat SG-VA Series</td>
<td>2019-04-08T11:27:32</td>
<td>192.168.1.207</td>
<td>sgos6x</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h3 id="get-device-information">2. Get device information</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Gets device information from Symantec MC.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-1">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>symantec-mc-get-device</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-1">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 134px;"><strong>Argument Name</strong></th>
<th style="width: 534px;"><strong>Description</strong></th>
<th style="width: 72px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 134px;">uuid</td>
<td style="width: 534px;">Device UUID. Run the symantec-mc-list-devices command to get the UUID.</td>
<td style="width: 72px;">Required</td>
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
<table style="width: 748px;">
<thead>
<tr>
<th style="width: 368px;"><strong>Path</strong></th>
<th style="width: 64px;"><strong>Type</strong></th>
<th style="width: 308px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 368px;">SymantecMC.Device.UUID</td>
<td style="width: 64px;">String</td>
<td style="width: 308px;">Device UUID.</td>
</tr>
<tr>
<td style="width: 368px;">SymantecMC.Device.Name</td>
<td style="width: 64px;">String</td>
<td style="width: 308px;">Device name.</td>
</tr>
<tr>
<td style="width: 368px;">SymantecMC.Device.LastChanged</td>
<td style="width: 64px;">String</td>
<td style="width: 308px;">Device last changed date.</td>
</tr>
<tr>
<td style="width: 368px;">SymantecMC.Device.LastChangedBy</td>
<td style="width: 64px;">String</td>
<td style="width: 308px;">User that last changed the device.</td>
</tr>
<tr>
<td style="width: 368px;">SymantecMC.Device.Description</td>
<td style="width: 64px;">String</td>
<td style="width: 308px;">Device description.</td>
</tr>
<tr>
<td style="width: 368px;">SymantecMC.Device.Model</td>
<td style="width: 64px;">String</td>
<td style="width: 308px;">Device model.</td>
</tr>
<tr>
<td style="width: 368px;">SymantecMC.Device…Platform</td>
<td style="width: 64px;">String</td>
<td style="width: 308px;">Device platform</td>
</tr>
<tr>
<td style="width: 368px;">SymantecMC.Device.Type</td>
<td style="width: 64px;">String</td>
<td style="width: 308px;">Device type.</td>
</tr>
<tr>
<td style="width: 368px;">SymantecMC.Device.OSVersion</td>
<td style="width: 64px;">String</td>
<td style="width: 308px;">Device OS version.</td>
</tr>
<tr>
<td style="width: 368px;">SymantecMC.Device.Build</td>
<td style="width: 64px;">Number</td>
<td style="width: 308px;">Device build number.</td>
</tr>
<tr>
<td style="width: 368px;">SymantecMC.Device.SerialNumber</td>
<td style="width: 64px;">Number</td>
<td style="width: 308px;">Device serial number.</td>
</tr>
<tr>
<td style="width: 368px;">SymantecMC.Device.Host</td>
<td style="width: 64px;">String</td>
<td style="width: 308px;">Device host address.</td>
</tr>
<tr>
<td style="width: 368px;">SymantecMC.Device.ManagementStatus</td>
<td style="width: 64px;">String</td>
<td style="width: 308px;">Device management status.</td>
</tr>
<tr>
<td style="width: 368px;">SymantecMC.Device.DeploymentStatus</td>
<td style="width: 64px;">String</td>
<td style="width: 308px;">Device deployment status.</td>
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
<pre>symantec-mc-get-device uuid="C131C3D1-171B-4DA7-ADE2-AA736EA91540"</pre>
</div>
<div class="cl-preview-section">
<h5 id="context-example-1">Context Example</h5>
</div>
<div class="cl-preview-section">
<pre>{
    "SymantecMC.Device": {
        "SerialNumber": "0806315479", 
        "Name": "192.168.1.207 - Blue Coat SG-VA Series", 
        "LastChangedBy": "admin", 
        "LastChanged": "2019-04-08T11:27:32", 
        "DeploymentStatus": "DEPLOYED", 
        "ManagementStatus": "FULLY_MANAGED", 
        "Platform": "Blue Coat SG-VA Series", 
        "Host": "192.168.1.207", 
        "Build": "226712", 
        "Model": "VSWG-SE", 
        "OSVersion": "SGOS 6.7.4.1 SWG Edition", 
        "Type": "sgos6x", 
        "UUID": "C131C3D1-171B-4DA7-ADE2-AA736EA91540"
    }
}
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-1">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<h3 id="symantec-management-center-device">Symantec Management Center Device</h3>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table border="2">
<thead>
<tr>
<th>UUID</th>
<th>Name</th>
<th>Last Changed</th>
<th>Last Changed By</th>
<th>Model</th>
<th>Platform</th>
<th>Host</th>
<th>Type</th>
<th>OS Version</th>
<th>Build</th>
<th>Serial Number</th>
<th>Management Status</th>
<th>Deployment Status</th>
</tr>
</thead>
<tbody>
<tr>
<td>C131C3D1-171B-4DA7-ADE2-AA736EA91540</td>
<td>192.168.1.207 - Blue Coat SG-VA Series</td>
<td>2019-04-08T11:27:32</td>
<td>admin</td>
<td>VSWG-SE</td>
<td>Blue Coat SG-VA Series</td>
<td>192.168.1.207</td>
<td>sgos6x</td>
<td>SGOS 6.7.4.1 SWG Edition</td>
<td>226712</td>
<td>0806315479</td>
<td>FULLY_MANAGED</td>
<td>DEPLOYED</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h3 id="get-device-health-information">3. Get device health information</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Gets health information for a device.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-2">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>symantec-mc-get-device-health</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-2">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 134px;"><strong>Argument Name</strong></th>
<th style="width: 534px;"><strong>Description</strong></th>
<th style="width: 72px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 134px;">uuid</td>
<td style="width: 534px;">Device UUID. Run the symantec-mc-list-devices command to get the UUID.</td>
<td style="width: 72px;">Required</td>
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
<th style="width: 404px;"><strong>Path</strong></th>
<th style="width: 73px;"><strong>Type</strong></th>
<th style="width: 263px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 404px;">SymantecMC.Device.UUID</td>
<td style="width: 73px;">String</td>
<td style="width: 263px;">Device UUID.</td>
</tr>
<tr>
<td style="width: 404px;">SymantecMC.Device.Name</td>
<td style="width: 73px;">String</td>
<td style="width: 263px;">Device name.</td>
</tr>
<tr>
<td style="width: 404px;">SymantecMC.Device.Health.Category</td>
<td style="width: 73px;">String</td>
<td style="width: 263px;">Device health category.</td>
</tr>
<tr>
<td style="width: 404px;">SymantecMC.Device.Health.Name</td>
<td style="width: 73px;">String</td>
<td style="width: 263px;">Device health name.</td>
</tr>
<tr>
<td style="width: 404px;">SymantecMC.Device.Health.State</td>
<td style="width: 73px;">String</td>
<td style="width: 263px;">Device health state.</td>
</tr>
<tr>
<td style="width: 404px;">SymantecMC.Device.Health.Message</td>
<td style="width: 73px;">String</td>
<td style="width: 263px;">Device health message.</td>
</tr>
<tr>
<td style="width: 404px;">SymantecMC.Device.Health.Status</td>
<td style="width: 73px;">String</td>
<td style="width: 263px;">Device health status.</td>
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
<pre>symantec-mc-get-device-health uuid="C131C3D1-171B-4DA7-ADE2-AA736EA91540"</pre>
</div>
<div class="cl-preview-section">
<h5 id="context-example-2">Context Example</h5>
</div>
<div class="cl-preview-section">
<pre>{
    "SymantecMC.Device": {
        "Health": [
            {
                "Category": "DNS Server", 
                "Status": "UP", 
                "Message": "Successes: 23374", 
                "Name": "dns.8.8.8.8", 
                "State": "OK"
            }, 
            {
                "Category": "External Services", 
                "Status": "UP", 
                "Message": "Successes: 796", 
                "Name": "drtr.rating_service", 
                "State": "OK"
            }
        ], 
        "Name": "192.168.1.207 - Blue Coat SG-VA Series", 
        "UUID": "C131C3D1-171B-4DA7-ADE2-AA736EA91540"
    }
}
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-2">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<h3 id="symantec-management-center-device-1">Symantec Management Center Device</h3>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table border="2">
<thead>
<tr>
<th>UUID</th>
<th>Name</th>
</tr>
</thead>
<tbody>
<tr>
<td>C131C3D1-171B-4DA7-ADE2-AA736EA91540</td>
<td>192.168.1.207 - Blue Coat SG-VA Series</td>
</tr>
</tbody>
</table>
</div>
</div>
<div class="cl-preview-section">
<h3 id="device-health">Device Health</h3>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table border="2">
<thead>
<tr>
<th>Category</th>
<th>Name</th>
<th>State</th>
<th>Message</th>
<th>Status</th>
</tr>
</thead>
<tbody>
<tr>
<td>DNS Server</td>
<td>dns.8.8.8.8</td>
<td>OK</td>
<td>Successes: 23374</td>
<td>UP</td>
</tr>
<tr>
<td>External Services</td>
<td>drtr.rating_service</td>
<td>OK</td>
<td>Successes: 796</td>
<td>UP</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h3 id="get-license-information-for-a-device">4. Get license information for a device</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Gets license information for a device in Symantec MC</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-3">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>symantec-mc-get-device-license</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-3">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 132px;"><strong>Argument Name</strong></th>
<th style="width: 536px;"><strong>Description</strong></th>
<th style="width: 72px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 132px;">uuid</td>
<td style="width: 536px;">Device UUID. Run the symantec-mc-list-devices command to get the UUID.</td>
<td style="width: 72px;">Required</td>
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
<th style="width: 397px;"><strong>Path</strong></th>
<th style="width: 40px;"><strong>Type</strong></th>
<th style="width: 303px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 397px;">SymantecMC.Device.UUID</td>
<td style="width: 40px;">String</td>
<td style="width: 303px;">Device UUID.</td>
</tr>
<tr>
<td style="width: 397px;">SymantecMC.Device.Name</td>
<td style="width: 40px;">String</td>
<td style="width: 303px;">Device name.</td>
</tr>
<tr>
<td style="width: 397px;">SymantecMC.Device.Type</td>
<td style="width: 40px;">String</td>
<td style="width: 303px;">Device type.</td>
</tr>
<tr>
<td style="width: 397px;">SymantecMC.Device.LicenseStatus</td>
<td style="width: 40px;">String</td>
<td style="width: 303px;">Device license status.</td>
</tr>
<tr>
<td style="width: 397px;">SymantecMC.Device.LicenseComponent.Name</td>
<td style="width: 40px;">String</td>
<td style="width: 303px;">Device license component name.</td>
</tr>
<tr>
<td style="width: 397px;">SymantecMC.Device.LicenseComponent.ActivationDate</td>
<td style="width: 40px;">Date</td>
<td style="width: 303px;">Device license component activation date.</td>
</tr>
<tr>
<td style="width: 397px;">SymantecMC.Device.LicenseComponent.ExpirationDate</td>
<td style="width: 40px;">Date</td>
<td style="width: 303px;">Device license component expiration date</td>
</tr>
<tr>
<td style="width: 397px;">SymantecMC.Device.LicenseComponent.Validity</td>
<td style="width: 40px;">String</td>
<td style="width: 303px;">Device license component validity.</td>
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
<pre>symantec-mc-get-device-license uuid="C131C3D1-171B-4DA7-ADE2-AA736EA91540"</pre>
</div>
<div class="cl-preview-section">
<h5 id="context-example-3">Context Example</h5>
</div>
<div class="cl-preview-section">
<pre>{
    "SymantecMC.Device": {
        "LicenseComponent": [
            {
                "ActivationDate": "2019-03-25T00:00:00", 
                "ExpirationDate": "2019-09-24T00:00:00", 
                "Validity": "VALID", 
                "Name": "SGOS 6 SWG Edition"
            }, 
            {
                "ActivationDate": "2019-03-25T00:00:00", 
                "ExpirationDate": "2019-09-24T00:00:00", 
                "Validity": "VALID", 
                "Name": "Windows Media Streaming"
            }, 
            {
                "ActivationDate": "2019-03-25T00:00:00", 
                "ExpirationDate": "2019-09-24T00:00:00", 
                "Validity": "VALID", 
                "Name": "Real Media Streaming"
            }, 
            {
                "ActivationDate": "2019-03-25T00:00:00", 
                "ExpirationDate": "2019-09-24T00:00:00", 
                "Validity": "VALID", 
                "Name": "QuickTime Streaming"
            }, 
            {
                "ActivationDate": "2019-03-25T00:00:00", 
                "ExpirationDate": "2019-09-24T00:00:00", 
                "Validity": "VALID", 
                "Name": "SSL"
            }, 
            {
                "ActivationDate": "2019-03-25T00:00:00", 
                "ExpirationDate": "2019-09-24T00:00:00", 
                "Validity": "VALID", 
                "Name": "Bandwidth Management"
            }, 
            {
                "ActivationDate": "2019-03-25T00:00:00", 
                "ExpirationDate": "2019-09-24T00:00:00", 
                "Validity": "VALID", 
                "Name": "ProxyClient - Acceleration"
            }, 
            {
                "ActivationDate": "2019-03-25T00:00:00", 
                "ExpirationDate": "2019-09-24T00:00:00", 
                "Validity": "VALID", 
                "Name": "ProxyClient - Web Filtering"
            }, 
            {
                "ActivationDate": "2019-03-25T00:00:00", 
                "ExpirationDate": "2019-09-24T00:00:00", 
                "Validity": "VALID", 
                "Name": "3rd Party Onbox Content Filtering"
            }, 
            {
                "ActivationDate": "2019-03-25T00:00:00", 
                "ExpirationDate": "2019-09-24T00:00:00", 
                "Validity": "VALID", 
                "Name": "ICAP Services"
            }, 
            {
                "ActivationDate": "2019-03-25T00:00:00", 
                "ExpirationDate": "2019-09-24T00:00:00", 
                "Validity": "VALID", 
                "Name": "AOL Instant Messaging"
            }, 
            {
                "ActivationDate": "2019-03-25T00:00:00", 
                "ExpirationDate": "2019-09-24T00:00:00", 
                "Validity": "VALID", 
                "Name": "MSN Instant Messaging"
            }, 
            {
                "ActivationDate": "2019-03-25T00:00:00", 
                "ExpirationDate": "2019-09-24T00:00:00", 
                "Validity": "VALID", 
                "Name": "Yahoo Instant Messaging"
            }, 
            {
                "ActivationDate": "2019-03-25T00:00:00", 
                "ExpirationDate": "2019-09-24T00:00:00", 
                "Validity": "VALID", 
                "Name": "Netegrity SiteMinder"
            }, 
            {
                "ActivationDate": "2019-03-25T00:00:00", 
                "ExpirationDate": "2019-09-24T00:00:00", 
                "Validity": "VALID", 
                "Name": "Oracle COREid"
            }, 
            {
                "ActivationDate": "2019-03-25T00:00:00", 
                "ExpirationDate": "2019-09-24T00:00:00", 
                "Validity": "VALID", 
                "Name": "Peer-To-Peer"
            }, 
            {
                "ActivationDate": "2019-03-25T00:00:00", 
                "ExpirationDate": "2019-09-24T00:00:00", 
                "Validity": "VALID", 
                "Name": "Compression"
            }, 
            {
                "ActivationDate": "2019-03-25T00:00:00", 
                "ExpirationDate": "2019-09-24T00:00:00", 
                "Validity": "VALID", 
                "Name": "Flash Streaming"
            }, 
            {
                "ActivationDate": "2019-03-25T00:00:00", 
                "ExpirationDate": "2019-09-24T00:00:00", 
                "Validity": "VALID", 
                "Name": "Encrypted Tap"
            }, 
            {
                "ActivationDate": "2019-04-25T00:00:00", 
                "ExpirationDate": "2019-09-24T00:00:00", 
                "Validity": "VALID", 
                "Name": "Authentication"
            }
        ], 
        "Type": "sgos6x", 
        "Name": "192.168.1.207 - Blue Coat SG-VA Series", 
        "UUID": "C131C3D1-171B-4DA7-ADE2-AA736EA91540"
    }
}
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-3">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<h3 id="symantec-management-center-device-2">Symantec Management Center Device</h3>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table border="2">
<thead>
<tr>
<th>UUID</th>
<th>Name</th>
<th>Type</th>
</tr>
</thead>
<tbody>
<tr>
<td>C131C3D1-171B-4DA7-ADE2-AA736EA91540</td>
<td>192.168.1.207 - Blue Coat SG-VA Series</td>
<td>sgos6x</td>
</tr>
</tbody>
</table>
</div>
</div>
<div class="cl-preview-section">
<h3 id="license-components">License Components</h3>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table border="2">
<thead>
<tr>
<th>Name</th>
<th>Activation Date</th>
<th>Expiration Date</th>
<th>Validity</th>
</tr>
</thead>
<tbody>
<tr>
<td>SGOS 6 SWG Edition</td>
<td>2019-03-25T00:00:00</td>
<td>2019-09-24T00:00:00</td>
<td>VALID</td>
</tr>
<tr>
<td>Windows Media Streaming</td>
<td>2019-03-25T00:00:00</td>
<td>2019-09-24T00:00:00</td>
<td>VALID</td>
</tr>
<tr>
<td>Real Media Streaming</td>
<td>2019-03-25T00:00:00</td>
<td>2019-09-24T00:00:00</td>
<td>VALID</td>
</tr>
<tr>
<td>QuickTime Streaming</td>
<td>2019-03-25T00:00:00</td>
<td>2019-09-24T00:00:00</td>
<td>VALID</td>
</tr>
<tr>
<td>SSL</td>
<td>2019-03-25T00:00:00</td>
<td>2019-09-24T00:00:00</td>
<td>VALID</td>
</tr>
<tr>
<td>Bandwidth Management</td>
<td>2019-03-25T00:00:00</td>
<td>2019-09-24T00:00:00</td>
<td>VALID</td>
</tr>
<tr>
<td>ProxyClient - Acceleration</td>
<td>2019-03-25T00:00:00</td>
<td>2019-09-24T00:00:00</td>
<td>VALID</td>
</tr>
<tr>
<td>ProxyClient - Web Filtering</td>
<td>2019-03-25T00:00:00</td>
<td>2019-09-24T00:00:00</td>
<td>VALID</td>
</tr>
<tr>
<td>3rd Party Onbox Content Filtering</td>
<td>2019-03-25T00:00:00</td>
<td>2019-09-24T00:00:00</td>
<td>VALID</td>
</tr>
<tr>
<td>ICAP Services</td>
<td>2019-03-25T00:00:00</td>
<td>2019-09-24T00:00:00</td>
<td>VALID</td>
</tr>
<tr>
<td>AOL Instant Messaging</td>
<td>2019-03-25T00:00:00</td>
<td>2019-09-24T00:00:00</td>
<td>VALID</td>
</tr>
<tr>
<td>MSN Instant Messaging</td>
<td>2019-03-25T00:00:00</td>
<td>2019-09-24T00:00:00</td>
<td>VALID</td>
</tr>
<tr>
<td>Yahoo Instant Messaging</td>
<td>2019-03-25T00:00:00</td>
<td>2019-09-24T00:00:00</td>
<td>VALID</td>
</tr>
<tr>
<td>Netegrity SiteMinder</td>
<td>2019-03-25T00:00:00</td>
<td>2019-09-24T00:00:00</td>
<td>VALID</td>
</tr>
<tr>
<td>Oracle COREid</td>
<td>2019-03-25T00:00:00</td>
<td>2019-09-24T00:00:00</td>
<td>VALID</td>
</tr>
<tr>
<td>Peer-To-Peer</td>
<td>2019-03-25T00:00:00</td>
<td>2019-09-24T00:00:00</td>
<td>VALID</td>
</tr>
<tr>
<td>Compression</td>
<td>2019-03-25T00:00:00</td>
<td>2019-09-24T00:00:00</td>
<td>VALID</td>
</tr>
<tr>
<td>Flash Streaming</td>
<td>2019-03-25T00:00:00</td>
<td>2019-09-24T00:00:00</td>
<td>VALID</td>
</tr>
<tr>
<td>Encrypted Tap</td>
<td>2019-03-25T00:00:00</td>
<td>2019-09-24T00:00:00</td>
<td>VALID</td>
</tr>
<tr>
<td>Authentication</td>
<td>2019-04-25T00:00:00</td>
<td>2019-09-24T00:00:00</td>
<td>VALID</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h3 id="get-the-status-of-a-device">5. Get the status of a device</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Gets the status of a device.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-4">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>symantec-mc-get-device-status</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-4">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 134px;"><strong>Argument Name</strong></th>
<th style="width: 534px;"><strong>Description</strong></th>
<th style="width: 72px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 134px;">uuid</td>
<td style="width: 534px;">Device UUID. Run the symantec-mc-list-devices command to get the UUID.</td>
<td style="width: 72px;">Required</td>
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
<th style="width: 386px;"><strong>Path</strong></th>
<th style="width: 96px;"><strong>Type</strong></th>
<th style="width: 258px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 386px;">SymantecMC.Device.UUID</td>
<td style="width: 96px;">String</td>
<td style="width: 258px;">Device UUID.</td>
</tr>
<tr>
<td style="width: 386px;">SymantecMC.Device.Name</td>
<td style="width: 96px;">String</td>
<td style="width: 258px;">Device name.</td>
</tr>
<tr>
<td style="width: 386px;">SymantecMC.Device.CheckDate</td>
<td style="width: 96px;">Date</td>
<td style="width: 258px;">Device check date.</td>
</tr>
<tr>
<td style="width: 386px;">SymantecMC.Device.StartDate</td>
<td style="width: 96px;">Date</td>
<td style="width: 258px;">Device start date.</td>
</tr>
<tr>
<td style="width: 386px;">SymantecMC.Device.MonitorState</td>
<td style="width: 96px;">String</td>
<td style="width: 258px;">Device monitor state.</td>
</tr>
<tr>
<td style="width: 386px;">SymantecMC.Device.Warnings</td>
<td style="width: 96px;">Number</td>
<td style="width: 258px;">Device warning count.</td>
</tr>
<tr>
<td style="width: 386px;">SymantecMC.Device.Errors</td>
<td style="width: 96px;">Number</td>
<td style="width: 258px;">Device error count.</td>
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
<pre>symantec-mc-get-device-status uuid="C131C3D1-171B-4DA7-ADE2-AA736EA91540"</pre>
</div>
<div class="cl-preview-section">
<h5 id="context-example-4">Context Example</h5>
</div>
<div class="cl-preview-section">
<pre>{
    "SymantecMC.Device": {
        "StartDate": "2019-03-25T12:37:42", 
        "Errors": 0, 
        "Name": "192.168.1.207 - Blue Coat SG-VA Series", 
        "Warnings": 0, 
        "MonitorState": "MONITORED", 
        "CheckDate": "2019-04-28T13:05:40", 
        "UUID": "C131C3D1-171B-4DA7-ADE2-AA736EA91540"
    }
}
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-4">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<h3 id="symantec-management-center-device-status">Symantec Management Center Device Status</h3>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table border="2">
<thead>
<tr>
<th>UUID</th>
<th>Name</th>
<th>Check Date</th>
<th>Start Date</th>
<th>Monitor State</th>
<th>Warnings</th>
<th>Errors</th>
</tr>
</thead>
<tbody>
<tr>
<td>C131C3D1-171B-4DA7-ADE2-AA736EA91540</td>
<td>192.168.1.207 - Blue Coat SG-VA Series</td>
<td>2019-04-28T13:05:40</td>
<td>2019-03-25T12:37:42</td>
<td>MONITORED</td>
<td>0</td>
<td>0</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h3 id="get-a-list-of-policies">6. Get a list of policies</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>List policies in Symantec MC.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-5">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>symantec-mc-list-policies</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-5">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 157px;"><strong>Argument Name</strong></th>
<th style="width: 512px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 157px;">content_type</td>
<td style="width: 512px;">Filter the query filter parameter by content type of policy, e.g., “ENDSWITH URL”</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 157px;">description</td>
<td style="width: 512px;">Filter the query filter parameter by description, for example: “CONTAINS desc.”</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 157px;">name</td>
<td style="width: 512px;">Filter the query filter parameter by name, for example: “STARTSWITH my_list”.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 157px;">reference_id</td>
<td style="width: 512px;">Filter the query filter parameter by referenceId, for example: “EQ my_list”.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 157px;">shared</td>
<td style="width: 512px;">Parameter to filter, based on whether the policy is shared or not shared.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 157px;">tenant</td>
<td style="width: 512px;">Filter the query filter parameter by tenant, e.g., “EQ TENANT_EXTERNAL_ID”</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 157px;">limit</td>
<td style="width: 512px;">Limit the number of results returned</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h5 id="context-output-5">Context Output</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 376px;"><strong>Path</strong></th>
<th style="width: 90px;"><strong>Type</strong></th>
<th style="width: 274px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 376px;">SymantecMC.Policy.UUID</td>
<td style="width: 90px;">String</td>
<td style="width: 274px;">Policy UUID.</td>
</tr>
<tr>
<td style="width: 376px;">SymantecMC.Policy.Name</td>
<td style="width: 90px;">String</td>
<td style="width: 274px;">Policy name.</td>
</tr>
<tr>
<td style="width: 376px;">SymantecMC.Policy.ContentType</td>
<td style="width: 90px;">String</td>
<td style="width: 274px;">Policy content type.</td>
</tr>
<tr>
<td style="width: 376px;">SymantecMC.Policy.Author</td>
<td style="width: 90px;">String</td>
<td style="width: 274px;">Policy author.</td>
</tr>
<tr>
<td style="width: 376px;">SymantecMC.Policy.Shared</td>
<td style="width: 90px;">Boolean</td>
<td style="width: 274px;">Policy shared.</td>
</tr>
<tr>
<td style="width: 376px;">SymantecMC.Policy.ReferenceID</td>
<td style="width: 90px;">String</td>
<td style="width: 274px;">Policy reference ID</td>
</tr>
<tr>
<td style="width: 376px;">SymantecMC.Policy.Tenant</td>
<td style="width: 90px;">String</td>
<td style="width: 274px;">Policy tenant.</td>
</tr>
<tr>
<td style="width: 376px;">SymantecMC.ReplaceVariables</td>
<td style="width: 90px;">Boolean</td>
<td style="width: 274px;">Policy replace variables.</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h5 id="command-example-5">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>symantec-mc-list-policies content_type="EQ IP_LIST"</pre>
</div>
<div class="cl-preview-section">
<h5 id="context-example-5">Context Example</h5>
</div>
<div class="cl-preview-section">
<pre>{
    "SymantecMC.Policy": [
        {
            "ReferenceID": "test_ip_list", 
            "ContentType": "IP_LIST", 
            "Name": "test_ip_list", 
            "Author": "admin", 
            "ReplaceVariables": true, 
            "Shared": true, 
            "UUID": "0D264052-9628-4872-8C07-E04A8B95F602"
        }, 
        {
            "ReferenceID": "test_policy_ip", 
            "ContentType": "IP_LIST", 
            "Name": "test_policy_ip", 
            "Author": "admin", 
            "ReplaceVariables": false, 
            "Shared": true, 
            "Tenant": "1234", 
            "UUID": "AF193330-49D0-413B-8365-6C4A5FD7A780"
        }
    ]
}
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-5">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<h3 id="symantec-management-center-policies">Symantec Management Center Policies</h3>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table border="2">
<thead>
<tr>
<th>UUID</th>
<th>Name</th>
<th>Content Type</th>
<th>Author</th>
<th>Shared</th>
<th>Reference ID</th>
<th>Tenant</th>
<th>Replace Variables</th>
</tr>
</thead>
<tbody>
<tr>
<td>0D264052-9628-4872-8C07-E04A8B95F602</td>
<td>test_ip_list</td>
<td>IP_LIST</td>
<td>admin</td>
<td>true</td>
<td>test_ip_list</td>
<td> </td>
<td>true</td>
</tr>
<tr>
<td>AF193330-49D0-413B-8365-6C4A5FD7A780</td>
<td>test_policy_ip</td>
<td>IP_LIST</td>
<td>admin</td>
<td>true</td>
<td>test_policy_ip</td>
<td>1234</td>
<td>false</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h3 id="get-policy-information">7. Get policy information</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Gets information for a policy.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-6">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>symantec-mc-get-policy</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-6">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 748px;">
<thead>
<tr>
<th style="width: 138px;"><strong>Argument Name</strong></th>
<th style="width: 530px;"><strong>Description</strong></th>
<th style="width: 72px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 138px;">uuid</td>
<td style="width: 530px;">Device UUID. Run the symantec-mc-list-devices command to get the UUID.</td>
<td style="width: 72px;">Optional</td>
</tr>
<tr>
<td style="width: 138px;">name</td>
<td style="width: 530px;">The policy name</td>
<td style="width: 72px;">Optional</td>
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
<th style="width: 381px;"><strong>Path</strong></th>
<th style="width: 64px;"><strong>Type</strong></th>
<th style="width: 295px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 381px;">SymantecMC.Policy.Name</td>
<td style="width: 64px;">String</td>
<td style="width: 295px;">Policy name.</td>
</tr>
<tr>
<td style="width: 381px;">SymantecMC.Policy.SchemaVersion</td>
<td style="width: 64px;">Number</td>
<td style="width: 295px;">Policy content schema version.</td>
</tr>
<tr>
<td style="width: 381px;">SymantecMC.Policy.RevisionInfo.Number</td>
<td style="width: 64px;">Number</td>
<td style="width: 295px;">Policy content revision number.</td>
</tr>
<tr>
<td style="width: 381px;">SymantecMC.Policy.RevisionInfo.Description</td>
<td style="width: 64px;">String</td>
<td style="width: 295px;">Policy content revision description.</td>
</tr>
<tr>
<td style="width: 381px;">SymantecMC.Policy.RevisionInfo.Author</td>
<td style="width: 64px;">String</td>
<td style="width: 295px;">Policy content revision author.</td>
</tr>
<tr>
<td style="width: 381px;">SymantecMC.Policy.RevisionInfo.Date</td>
<td style="width: 64px;">Date</td>
<td style="width: 295px;">Policy content revision date.</td>
</tr>
<tr>
<td style="width: 381px;">SymantecMC.Policy.IP.Address</td>
<td style="width: 64px;">String</td>
<td style="width: 295px;">Policy IP address.</td>
</tr>
<tr>
<td style="width: 381px;">SymantecMC.Policy.IP.Description</td>
<td style="width: 64px;">String</td>
<td style="width: 295px;">Policy IP description.</td>
</tr>
<tr>
<td style="width: 381px;">SymantecMC.Policy.IP.Enabled</td>
<td style="width: 64px;">Boolean</td>
<td style="width: 295px;">Policy IP enabled.</td>
</tr>
<tr>
<td style="width: 381px;">SymantecMC.Policy.URL.Address</td>
<td style="width: 64px;">String</td>
<td style="width: 295px;">Policy URL address.</td>
</tr>
<tr>
<td style="width: 381px;">SymantecMC.Policy.URL.Description</td>
<td style="width: 64px;">String</td>
<td style="width: 295px;">Policy URL description.</td>
</tr>
<tr>
<td style="width: 381px;">SymantecMC.Policy.URL.Enabled</td>
<td style="width: 64px;">Boolean</td>
<td style="width: 295px;">Policy URL enabled.</td>
</tr>
<tr>
<td style="width: 381px;">SymantecMC.Policy.Category.Name</td>
<td style="width: 64px;">String</td>
<td style="width: 295px;">Policy category name.</td>
</tr>
<tr>
<td style="width: 381px;">SymantecMC.Policy.UUID</td>
<td style="width: 64px;">String</td>
<td style="width: 295px;">Policy UUID.</td>
</tr>
<tr>
<td style="width: 381px;">SymantecMC.Policy.Description</td>
<td style="width: 64px;">String</td>
<td style="width: 295px;">Policy Description.</td>
</tr>
<tr>
<td style="width: 381px;">SymantecMC.Policy.ReferenceID</td>
<td style="width: 64px;">String</td>
<td style="width: 295px;">Policy reference ID.</td>
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
<pre>symantec-mc-get-policy uuid="0D264052-9628-4872-8C07-E04A8B95F602"</pre>
</div>
<div class="cl-preview-section">
<h5 id="context-example-6">Context Example</h5>
</div>
<div class="cl-preview-section">
<pre>{
    "SymantecMC.Policy": {
        "ReferenceID": "test_ip_list", 
        "ContentType": "IP_LIST", 
        "Description": "New description", 
        "IP": [
            {
                "Enabled": false, 
                "Description": "what?", 
                "Address": "1.2.3.4"
            }, 
            {
                "Enabled": false, 
                "Description": "Test IPs", 
                "Address": "8.8.8.8"
            }, 
            {
                "Enabled": false, 
                "Description": "Test IPs", 
                "Address": "8.8.8.8"
            }, 
            {
                "Enabled": false, 
                "Description": "Test IPs", 
                "Address": "8.8.8.8"
            }
        ], 
        "RevisionInfo": {
            "Date": "2019-04-28T13:03:46", 
            "Number": "1.13", 
            "Description": "test", 
            "Author": "admin"
        }, 
        "UUID": "0D264052-9628-4872-8C07-E04A8B95F602", 
        "SchemaVersion": "1.0", 
        "Name": "test_ip_list"
    }
}
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-6">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<h3 id="symantec-management-center-policy">Symantec Management Center Policy</h3>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table border="2">
<thead>
<tr>
<th>UUID</th>
<th>Name</th>
<th>Schema Version</th>
<th>Reference ID</th>
<th>Description</th>
<th>Content Type</th>
</tr>
</thead>
<tbody>
<tr>
<td>0D264052-9628-4872-8C07-E04A8B95F602</td>
<td>test_ip_list</td>
<td>1.0</td>
<td>test_ip_list</td>
<td>New description</td>
<td>IP_LIST</td>
</tr>
</tbody>
</table>
</div>
</div>
<div class="cl-preview-section">
<h3 id="revision-information">Revision Information</h3>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table border="2">
<thead>
<tr>
<th>Number</th>
<th>Description</th>
<th>Author</th>
<th>Date</th>
</tr>
</thead>
<tbody>
<tr>
<td>1.13</td>
<td>test</td>
<td>admin</td>
<td>2019-04-28T13:03:46</td>
</tr>
</tbody>
</table>
</div>
</div>
<div class="cl-preview-section">
<h3 id="ip-list">IP List</h3>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table border="2">
<thead>
<tr>
<th>Address</th>
<th>Description</th>
<th>Enabled</th>
</tr>
</thead>
<tbody>
<tr>
<td>1.2.3.4</td>
<td>what?</td>
<td>false</td>
</tr>
<tr>
<td>8.8.8.8</td>
<td>Test IPs</td>
<td>false</td>
</tr>
<tr>
<td>8.8.8.8</td>
<td>Test IPs</td>
<td>false</td>
</tr>
<tr>
<td>8.8.8.8</td>
<td>Test IPs</td>
<td>false</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h3 id="create-a-policy">8. Create a policy</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Creates a policy in Symantec MC.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-7">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>symantec-mc-create-policy</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-7">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 145px;"><strong>Argument Name</strong></th>
<th style="width: 524px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 145px;">name</td>
<td style="width: 524px;">Policy name.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 145px;">content_type</td>
<td style="width: 524px;">Policy content type.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 145px;">description</td>
<td style="width: 524px;">Policy description.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 145px;">reference_id</td>
<td style="width: 524px;">Policy reference ID.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 145px;">tenant</td>
<td style="width: 524px;">UUID of the tenant associated with this policy. Run the symantec-mc-list-tenants command to get the tenant UUID.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 145px;">shared</td>
<td style="width: 524px;">Share policy</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 145px;">replace_variables</td>
<td style="width: 524px;">Replace variables supported</td>
<td style="width: 71px;">Optional</td>
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
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 408px;"><strong>Path</strong></th>
<th style="width: 83px;"><strong>Type</strong></th>
<th style="width: 249px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 408px;">SymantecMC.Policy.UUID</td>
<td style="width: 83px;">String</td>
<td style="width: 249px;">Policy UUID.</td>
</tr>
<tr>
<td style="width: 408px;">SymantecMC.Policy.Name</td>
<td style="width: 83px;">String</td>
<td style="width: 249px;">Policy name.</td>
</tr>
<tr>
<td style="width: 408px;">SymantecMC.Policy.ContentType</td>
<td style="width: 83px;">String</td>
<td style="width: 249px;">Policy content type.</td>
</tr>
<tr>
<td style="width: 408px;">SymantecMC.Policy.Author</td>
<td style="width: 83px;">String</td>
<td style="width: 249px;">Policy author.</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h5 id="command-example-7">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>symantec-mc-create-policy name="test_ip_policy" content_type="IP_LIST" description="This is a test" tenant="EDAD4D73-95E7-4C11-84EB-D0C73D28D50A" shared="true"</pre>
</div>
<div class="cl-preview-section">
<h5 id="context-example-7">Context Example</h5>
</div>
<div class="cl-preview-section">
<pre>{
    "SymantecMC.Policy": {
        "UUID": "AFD91FAE-27C7-461A-86BB-317805ED8DCC", 
        "ContentType": "IP_LIST", 
        "Name": "test_ip_policy", 
        "Author": "admin"
    }
}
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-7">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<h3 id="policy-created-successfully">Policy created successfully</h3>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table border="2">
<thead>
<tr>
<th>UUID</th>
<th>Name</th>
<th>Content Type</th>
<th>Author</th>
</tr>
</thead>
<tbody>
<tr>
<td>AFD91FAE-27C7-461A-86BB-317805ED8DCC</td>
<td>test_ip_policy</td>
<td>IP_LIST</td>
<td>admin</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h3 id="update-a-policy">9. Update a policy</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Updates the metadata for a policy in Symantec MC.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-8">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>symantec-mc-update-policy</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-8">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 134px;"><strong>Argument Name</strong></th>
<th style="width: 533px;"><strong>Description</strong></th>
<th style="width: 73px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 134px;">uuid</td>
<td style="width: 533px;">Policy UUID. Run the symantec-mc-list-policies command to get the UUID.</td>
<td style="width: 73px;">Required</td>
</tr>
<tr>
<td style="width: 134px;">name</td>
<td style="width: 533px;">New name of the policy.</td>
<td style="width: 73px;">Optional</td>
</tr>
<tr>
<td style="width: 134px;">description</td>
<td style="width: 533px;">New description of the policy.</td>
<td style="width: 73px;">Optional</td>
</tr>
<tr>
<td style="width: 134px;">reference_id</td>
<td style="width: 533px;">New reference ID of the policy.</td>
<td style="width: 73px;">Optional</td>
</tr>
<tr>
<td style="width: 134px;">replace_variables</td>
<td style="width: 533px;">Replace variables in the policy.</td>
<td style="width: 73px;">Optional</td>
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
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 418px;"><strong>Path</strong></th>
<th style="width: 110px;"><strong>Type</strong></th>
<th style="width: 212px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 418px;">SymantecMC.Policy.UUID</td>
<td style="width: 110px;">String</td>
<td style="width: 212px;">Policy UUID.</td>
</tr>
<tr>
<td style="width: 418px;">SymantecMC.Policy.Name</td>
<td style="width: 110px;">String</td>
<td style="width: 212px;">Policy name.</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h5 id="command-example-8">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>symantec-mc-update-policy uuid="0D264052-9628-4872-8C07-E04A8B95F602" description="New description"</pre>
</div>
<div class="cl-preview-section">
<h5 id="context-example-8">Context Example</h5>
</div>
<div class="cl-preview-section">
<pre>{
    "SymantecMC.Policy": {
        "UUID": "0D264052-9628-4872-8C07-E04A8B95F602", 
        "ContentType": "IP_LIST", 
        "Name": "test_ip_list", 
        "Author": "admin"
    }
}
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-8">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<h3 id="policy-updated-successfully">Policy updated successfully</h3>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table border="2">
<thead>
<tr>
<th>UUID</th>
<th>Name</th>
<th>Content Type</th>
<th>Author</th>
</tr>
</thead>
<tbody>
<tr>
<td>0D264052-9628-4872-8C07-E04A8B95F602</td>
<td>test_ip_list</td>
<td>IP_LIST</td>
<td>admin</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h3 id="delete-a-policy">10. Delete a policy</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Deletes a policy in Symantec MC.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-9">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>symantec-mc-delete-policy</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-9">Input</h5>
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
<td style="width: 132px;">uuid</td>
<td style="width: 537px;">Policy UUID. Run the symantec-mc-list-policies command to get the UUID.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 132px;">force</td>
<td style="width: 537px;">Set to “true” to force the policy object to be removed even if it is referenced by another policy.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h5 id="context-output-9">Context Output</h5>
</div>
<div class="cl-preview-section">
<p>There is no context output for this command.</p>
</div>
<div class="cl-preview-section">
<h5 id="command-example-9">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>symantec-mc-delete-policy uuid="DCF96A1D-1D42-493A-B377-84E682D91BF1"</pre>
</div>
<div class="cl-preview-section">
<h5 id="context-example-9">Context Example</h5>
</div>
<div class="cl-preview-section">
<p>No context</p>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-9">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<p>Policy deleted successfully</p>
</div>
<div class="cl-preview-section">
<h3 id="get-a-list-of-tenants">11. Get a list of tenants</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>List tenants in Symantec MC.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-10">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>symantec-mc-list-tenants</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-10">Input</h5>
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
<td style="width: 198px;">limit</td>
<td style="width: 429px;">Maximum number of results to return.</td>
<td style="width: 113px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h5 id="context-output-10">Context Output</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 335px;"><strong>Path</strong></th>
<th style="width: 77px;"><strong>Type</strong></th>
<th style="width: 328px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 335px;">SymantecMC.Tenant.UUID</td>
<td style="width: 77px;">String</td>
<td style="width: 328px;">Tenant UUID.</td>
</tr>
<tr>
<td style="width: 335px;">SymantecMC.Tenant.Name</td>
<td style="width: 77px;">String</td>
<td style="width: 328px;">Tenant name.</td>
</tr>
<tr>
<td style="width: 335px;">SymantecMC.Tenant.ExternalID</td>
<td style="width: 77px;">String</td>
<td style="width: 328px;">Tenant external ID.</td>
</tr>
<tr>
<td style="width: 335px;">SymantecMC.Tenant.Description</td>
<td style="width: 77px;">String</td>
<td style="width: 328px;">Tenant description.</td>
</tr>
<tr>
<td style="width: 335px;">SymantecMC.Tenant.System</td>
<td style="width: 77px;">Boolean</td>
<td style="width: 328px;">Whether the system is a tenant.</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h5 id="command-example-10">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>symantec-mc-list-tenants</pre>
</div>
<div class="cl-preview-section">
<h5 id="context-example-10">Context Example</h5>
</div>
<div class="cl-preview-section">
<pre>{
    "SymantecMC.Tenant": [
        {
            "System": true, 
            "UUID": "54D4CDA9-293E-4861-B56F-0E50E5799F7A", 
            "ExternalID": "default", 
            "Description": "The tenant whose policy is used when no tenant-specific policy object is available.", 
            "Name": "Default"
        }, 
        {
            "UUID": "EDAD4D73-95E7-4C11-84EB-D0C73D28D50A", 
            "ExternalID": "1234", 
            "Name": "Tenant", 
            "System": false
        }
    ]
}
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-10">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<h3 id="symantec-management-center-tenants">Symantec Management Center Tenants</h3>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table border="2">
<thead>
<tr>
<th>UUID</th>
<th>Name</th>
<th>External ID</th>
<th>Description</th>
<th>System</th>
</tr>
</thead>
<tbody>
<tr>
<td>54D4CDA9-293E-4861-B56F-0E50E5799F7A</td>
<td>Default</td>
<td>default</td>
<td>The tenant whose policy is used when no tenant-specific policy object is available.</td>
<td>true</td>
</tr>
<tr>
<td>EDAD4D73-95E7-4C11-84EB-D0C73D28D50A</td>
<td>Tenant</td>
<td>1234</td>
<td> </td>
<td>false</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h3 id="add-content-to-a-policy">12. Add content to a policy</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Adds content to a policy in Symantec MC. Can be IPs, URLs, or category names.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-11">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>symantec-mc-add-policy-content</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-11">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 750px;">
<thead>
<tr>
<th><strong>Argument Name</strong></th>
<th><strong>Description</strong></th>
<th><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>uuid</td>
<td>Policy UUID. Run the symantec-mc-list-policies command to get the UUID.</td>
<td>Optional</td>
</tr>
<tr>
<td>name</td>
<td>The policy name to add content to.</td>
<td>Optional</td>
</tr>
<tr>
<td>content_type</td>
<td>Policy content type</td>
<td>Required</td>
</tr>
<tr>
<td>change_description</td>
<td>Description of the policy change.</td>
<td>Required</td>
</tr>
<tr>
<td>schema_version</td>
<td>The version of the schema for this content. This value will correspond to the format of the content. Run the symantec-mc-get-policy command to get the schema vesion.</td>
<td>Optional</td>
</tr>
<tr>
<td>ip</td>
<td>CSV list of IP addresses to add, for example: “1.2.3.4, 8.8.8.8”.</td>
<td>Optional</td>
</tr>
<tr>
<td>url</td>
<td>CSV list of URLs to add, for example: “www.google.com, www.github.com”.</td>
<td>Optional</td>
</tr>
<tr>
<td>category</td>
<td>CSV list of category names to add, for example: “Job Search/Careers, Content Servers”.</td>
<td>Optional</td>
</tr>
<tr>
<td>enabled</td>
<td>Relevant for URL and IP.</td>
<td>Optional</td>
</tr>
<tr>
<td>description</td>
<td>Content description.</td>
<td>Optional</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h5 id="context-output-11">Context Output</h5>
</div>
<div class="cl-preview-section">
<p>There is no context output for this command.</p>
</div>
<div class="cl-preview-section">
<h5 id="command-example-11">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>symantec-mc-add-policy-content uuid="0D264052-9628-4872-8C07-E04A8B95F602" content_type="IP_LIST" change_description="test" ip="2.2.2.2,4.4.4.4,8.8.8.8" description="Test IPs"</pre>
</div>
<div class="cl-preview-section">
<h5 id="context-example-11">Context Example</h5>
</div>
<div class="cl-preview-section">
<p>No context output</p>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-11">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<p>Successfully added content to the policy</p>
</div>
<div class="cl-preview-section">
<h3 id="delete-policy-content">13. Delete policy content</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Deletes content from a policy in Symantec MC.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-12">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>symantec-mc-delete-policy-content</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-12">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 146px;"><strong>Argument Name</strong></th>
<th style="width: 523px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 146px;">uuid</td>
<td style="width: 523px;">Policy UUID. Run the symantec-mc-list-policies command to get the UUID.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 146px;">name</td>
<td style="width: 523px;">The policy name to add content to.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 146px;">content_type</td>
<td style="width: 523px;">Policy content type.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 146px;">change_description</td>
<td style="width: 523px;">Description of the policy change.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 146px;">schema_version</td>
<td style="width: 523px;">The version of the schema for this content. This value will correspond to the format of the content. Run the symantec-mc-get-policy command to get the schema version.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 146px;">ip</td>
<td style="width: 523px;">CSV list of IP addresses to delete, for example: “1.2.3.4, 8.8.8.8”.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 146px;">url</td>
<td style="width: 523px;">CSV list of URLs to delete, for example: “www.google.com, www.github.com”.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 146px;">category</td>
<td style="width: 523px;">CSV list of category names to delete, for example: “Job Search/Careers, Content Servers”.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h5 id="context-output-12">Context Output</h5>
</div>
<div class="cl-preview-section">
<p>There is no context output for this command.</p>
</div>
<div class="cl-preview-section">
<h5 id="command-example-12">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>symantec-mc-delete-policy-content uuid="0D264052-9628-4872-8C07-E04A8B95F602" content_type="IP_LIST" change_description="test" ip="2.2.2.2,4.4.4.4"</pre>
</div>
<div class="cl-preview-section">
<h5 id="context-example-12">Context Example</h5>
</div>
<div class="cl-preview-section">
<p>No context output</p>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-12">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<p>Successfully deleted content from the policy</p>
</div>

<div class="cl-preview-section">
<h3 id="delete-policy-content">14. Update policy content</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Updates content in a policy in Symantec MC.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-12">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>symantec-mc-update-policy-content</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-12">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 146px;"><strong>Argument Name</strong></th>
<th style="width: 523px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 146px;">uuid</td>
<td style="width: 523px;">Policy UUID. Run the symantec-mc-list-policies command to get the UUID.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 146px;">name</td>
<td style="width: 523px;">The policy name to update content in.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 146px;">content_type</td>
<td style="width: 523px;">Policy content type.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 146px;">change_description</td>
<td style="width: 523px;">Description of the policy change.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 146px;">schema_version</td>
<td style="width: 523px;">The version of the schema for this content. This value will correspond to the format of the content. Run the symantec-mc-get-policy command to get the schema version.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 146px;">ip</td>
<td style="width: 523px;">CSV list of IP addresses to update, for example: “1.2.3.4, 8.8.8.8”.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 146px;">url</td>
<td style="width: 523px;">CSV list of URLs to update, for example: “www.google.com, www.github.com”.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 146px;">category</td>
<td style="width: 523px;">CSV list of category names to update, for example: “Job Search/Careers, Content Servers”.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td>enabled</td>
<td>Relevant for URL and IP.</td>
<td>Optional</td>
</tr>
<tr>
<td>description</td>
<td>Content description.</td>
<td>Optional</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h5 id="context-output-12">Context Output</h5>
</div>
<div class="cl-preview-section">
<p>There is no context output for this command.</p>
</div>
<div class="cl-preview-section">
<h5 id="command-example-12">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>symantec-mc-update-policy-content uuid="0D264052-9628-4872-8C07-E04A8B95F602" content_type="LOCAL_CATEGORY_DB" change_description="test" ip="2.2.2.2,4.4.4.4" description="updated comment"</pre>
</div>
<div class="cl-preview-section">
<h5 id="context-example-12">Context Example</h5>
</div>
<div class="cl-preview-section">
<p>No context output</p>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-12">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<p>Successfully updated content in the policy</p>
</div>
<div class="cl-preview-section">
<h2 id="additional-information">Additional Information</h2>
</div>
<div class="cl-preview-section">
<p>For additional details regarding Query Filter Syntax see the <a href="https://support.symantec.com/en_US/article.DOC11242.html" target="_blank" rel="noopener">Symantec Management Center API documentation</a>.</p>
<p>Currently the integrations supports managing content for shared objects of types:</p>
</div>
<div class="cl-preview-section">
<ul>
<li>URL List</li>
<li>IP List</li>
<li>Category List</li>
<li>Local Database Category List</li>
</ul>
<p>The API does not support running requests in parallel. An error will be thrown.</p>
</div>
<div class="cl-preview-section"> </div>
<div class="cl-preview-section">
<h2 id="troubleshooting">Troubleshooting</h2>
</div>
<div class="cl-preview-section">
<p>You may encounter the following errors while running Symantec MC commands:</p>
</div>
<div class="cl-preview-section">
<p><strong>HTTP 404 Not Found</strong> - The requested resource was not found. You can try to list the existing resources and search again.</p>
</div>
<div class="cl-preview-section">
<p><strong>HTTP 400 Bad Request</strong> - An incorrect request was sent to Symantec MC. Verify that you are sending the arguments correctly.</p>
</div>
<div class="cl-preview-section">
<p><strong>HTTP 500 Internal Server Error</strong> - Error in Symantec MC. Could occur if requests are made in parallel.</p>
</div>
<div class="cl-preview-section">
</div>