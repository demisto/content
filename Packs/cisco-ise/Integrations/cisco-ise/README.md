<!-- HTML_DOC -->
<p>Use the Cisco ISE integration to get endpoint data, and to manage and update endpoints and ANC policies.</p>
<p> </p>
<h2>Configure Cisco ISE on Cortex XSOAR</h2>
<p> </p>
<ol>
<li>Navigate to<span> </span><strong>Settings</strong><span> </span>&gt;<span> </span><strong>Integrations</strong><span> </span>&gt;<span> </span><strong>Servers &amp; Services</strong>.</li>
<li>Search for Cisco ISE.</li>
<li>Click<span> </span><strong>Add instance</strong><span> </span>to create and configure a new integration instance.
<ul>
<li>
<strong>Name</strong>: a textual name for the integration instance.</li>
<li><strong>Cisco ISE server URL (e.g., https://123.123.123.65 )</strong></li>
<li><strong>Server port (e.g., 9060)</strong></li>
<li><strong>Cisco ISE username</strong></li>
<li><strong>Use system proxy settings</strong></li>
<li><strong>Trust any certificate (not secure)</strong></li>
</ul>
</li>
<li>Click<span> </span><strong>Test</strong><span> </span>to validate the URLs, token, and connection.</li>
</ol>
<p> </p>
<h2>Commands</h2>
<p>You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
<p> </p>
<ol>
<li><a href="#h_5bf25414-e9b3-41fe-a855-1bf7de70d143" target="_self">Get an endpoint ID: cisco-ise-get-endpoint-id</a></li>
<li><a href="#h_37fa10a6-ffe9-4067-b7be-318ac5d26fa4" target="_self">Get information for an endpoint: cisco-ise-get-endpoint-details</a></li>
<li><a href="#h_8abfbaec-2876-47c4-b0d2-5d3bfd7854d4" target="_self">Re-authenticate an endpoint: cisco-ise-reauthenticate-endpoint</a></li>
<li><a href="#h_c03d2ed7-a21d-4081-a37a-53f011efed19" target="_self">Get data for all existing endpoints: cisco-ise-get-endpoints</a></li>
<li><a href="#h_b6845c4c-5eb7-4340-af4c-30e7c7349036" target="_self">Update custom attributes of an endpoint: cisco-ise-update-endpoint-custom-attribute</a></li>
<li><a href="#h_873ab8be-3282-4573-a1cb-25ce224ee813" target="_self">Update the group of an endpoint: cisco-ise-update-endpoint-group</a></li>
<li><a href="#h_df978421-5af4-47b9-933c-8bdb414c5176" target="_self">Get a collection of endpoint identity groups: cisco-ise-get-groups</a></li>
<li><a href="#h_636ec1ff-018e-45b1-8ac1-1fdd1c43cbaa" target="_self">Get all ANC policies: cisco-ise-get-policies</a></li>
<li><a href="#h_4be7bcf4-cba4-4762-beae-54a901e2eedd" target="_self">Get a single ANC policy: cisco-ise-get-policy</a></li>
<li><a href="#h_a62bd46e-8b18-4f75-9215-2c1305374a47" target="_self">Create an ANC policy: cisco-ise-create-policy</a></li>
<li><a href="#h_19abc45f-7827-416c-bbc4-2f2be27c6453" target="_self">Assign an ANC policy to an endpoint: cisco-ise-assign-policy</a></li>
<li><a href="#h_f60063f9-8c7f-4198-945e-829c34c16fcb" target="_self">Get all endpoints on block list: cisco-ise-get-blacklist-endpoints</a></li>
</ol>
<h3 id="h_5bf25414-e9b3-41fe-a855-1bf7de70d143">1. Get an endpoint ID</h3>
<hr>
<p>Returns an endpoint ID, by its MAC address.</p>
<h5>Base Command</h5>
<p><code>cisco-ise-get-endpoint-id</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 150px;"><strong>Argument Name</strong></th>
<th style="width: 505px;"><strong>Description</strong></th>
<th style="width: 85px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 150px;">macAddress</td>
<td style="width: 505px;">MAC address of the endpoint (format: 11:22:33:44:55:66).</td>
<td style="width: 85px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 324px;"><strong>Path</strong></th>
<th style="width: 80px;"><strong>Type</strong></th>
<th style="width: 336px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 324px;">Endpoint.ID</td>
<td style="width: 80px;">string</td>
<td style="width: 336px;">Endpoint ID.</td>
</tr>
<tr>
<td style="width: 324px;">Endpoint.MACAddress</td>
<td style="width: 80px;">string</td>
<td style="width: 336px;">Endpoint MAC address.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!cisco-ise-get-endpoint-id macAddress=00:0E:35:D4:D8:51</pre>
<h5>Human Readable Output</h5>
<h3>The endpoint ID is: 327b0120-4ba1-11e8-93bd-000c296ec148</h3>
<h3 id="h_37fa10a6-ffe9-4067-b7be-318ac5d26fa4">2. Get information for an endpoint</h3>
<hr>
<p>Returns details for a specified endpoint.</p>
<h5>Base Command</h5>
<p><code>cisco-ise-get-endpoint-details</code></p>
<h5>Input</h5>
<p> </p>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 161px;"><strong>Argument Name</strong></th>
<th style="width: 493px;"><strong>Description</strong></th>
<th style="width: 86px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 161px;">endpointID</td>
<td style="width: 493px;">The ID of the endpoint for which to return details.</td>
<td style="width: 86px;">Optional</td>
</tr>
<tr>
<td style="width: 161px;">macAddress</td>
<td style="width: 493px;">MAC address of the endpoint (format 11:22:33:44:55:66).</td>
<td style="width: 86px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<p> </p>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 305px;"><strong>Path</strong></th>
<th style="width: 52px;"><strong>Type</strong></th>
<th style="width: 383px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 305px;">CiscoISE.Endpoint.ID</td>
<td style="width: 52px;">string</td>
<td style="width: 383px;">Endpoint ID.</td>
</tr>
<tr>
<td style="width: 305px;">CiscoISE.Endpoint.Description</td>
<td style="width: 52px;">string</td>
<td style="width: 383px;">Endpoint description.</td>
</tr>
<tr>
<td style="width: 305px;">CiscoISE.Endpoint.MACAddress</td>
<td style="width: 52px;">string</td>
<td style="width: 383px;">Endpoint MAC address.</td>
</tr>
<tr>
<td style="width: 305px;">CiscoISE.Endpoint.Group</td>
<td style="width: 52px;">string</td>
<td style="width: 383px;">Endpoint group name</td>
</tr>
<tr>
<td style="width: 305px;">Endpoint.ID</td>
<td style="width: 52px;">string</td>
<td style="width: 383px;">Endpoint ID.</td>
</tr>
<tr>
<td style="width: 305px;">Endpoint.MACAddress</td>
<td style="width: 52px;">string</td>
<td style="width: 383px;">Endpoint MAC address.</td>
</tr>
<tr>
<td style="width: 305px;">CiscoISE.Endpoint.CustomAttributes</td>
<td style="width: 52px;">string</td>
<td style="width: 383px;">Endpoint custom attributes.</td>
</tr>
<tr>
<td style="width: 305px;">CiscoISE.Endpoint.StaticGroupAssignment</td>
<td style="width: 52px;">boolean</td>
<td style="width: 383px;">True if the endpoint has a static group assignment.</td>
</tr>
<tr>
<td style="width: 305px;">CiscoISE.Endpoint.StaticProfileAssignment</td>
<td style="width: 52px;">boolean</td>
<td style="width: 383px;">Whether the endpoint has a static profile assignment.</td>
</tr>
<tr>
<td style="width: 305px;">CiscoISE.Endpoint.User</td>
<td style="width: 52px;">string</td>
<td style="width: 383px;">Profile of the user associated with the endpoint.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<p> </p>
<pre>!cisco-ise-get-endpoint-details endpointID=327b0120-4ba1-11e8-93bd-000c296ec148</pre>
<p> </p>
<h5>Context Example</h5>
<p> </p>
<pre>{
    "CiscoISE.Endpoint": {
        "MACAddress": "00:0E:35:D4:D8:51", 
        "Group": "Internal Dev", 
        "ID": "327b0120-4ba1-11e8-93bd-000c296ec148", 
        "StaticProfileAssignment": false, 
        "StaticGroupAssignment": false
    }, 
    "Endpoint": {
        "MACAddress": "00:0E:35:D4:D8:51", 
        "ID": "327b0120-4ba1-11e8-93bd-000c296ec148"
    }
}
</pre>
<h5>Human Readable Output</h5>
<h3>Endpoint details - 327b0120-4ba1-11e8-93bd-000c296ec148</h3>
<table border="2">
<thead>
<tr>
<th>Group</th>
<th>ID</th>
<th>MACAddress</th>
<th>StaticGroupAssignment</th>
<th>StaticProfileAssignment</th>
</tr>
</thead>
<tbody>
<tr>
<td>Internal Dev</td>
<td>327b0120-4ba1-11e8-93bd-000c296ec148</td>
<td>00:0E:35:D4:D8:51</td>
<td>false</td>
<td>false</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_8abfbaec-2876-47c4-b0d2-5d3bfd7854d4">3. Re-authenticate an endpoint</h3>
<hr>
<p>Re-authenticates an endpoint (Change of Authorization - CoA).</p>
<h5>Base Command</h5>
<p><code>cisco-ise-reauthenticate-endpoint</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 149px;"><strong>Argument Name</strong></th>
<th style="width: 505px;"><strong>Description</strong></th>
<th style="width: 86px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 149px;">macAddress</td>
<td style="width: 505px;">MAC address of the endpoint (format 11:22:33:44:55:66).</td>
<td style="width: 86px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<p> </p>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 383px;"><strong>Path</strong></th>
<th style="width: 72px;"><strong>Type</strong></th>
<th style="width: 285px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 383px;">CiscoISE.Endpoint.MACAddress</td>
<td style="width: 72px;">string</td>
<td style="width: 285px;">MAC address of the endpoint.</td>
</tr>
<tr>
<td style="width: 383px;">CiscoISE.Endpoint.reauthenticateResult</td>
<td style="width: 72px;">boolean</td>
<td style="width: 285px;">Re-authentication result.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!cisco-ise-reauthenticate-endpoint macAddress=00:0E:35:D4:D8:51</pre>
<h5>Human Readable Output</h5>
<h3>'Activation result was : True</h3>
<h3 id="h_c03d2ed7-a21d-4081-a37a-53f011efed19">4. Get data for all existing endpoints</h3>
<hr>
<p>Returns data for existing endpoints.</p>
<h5>Base Command</h5>
<p><code>cisco-ise-get-endpoints</code></p>
<h5>Input</h5>
<p>There are no arguments for this command.</p>
<h5>Context Output</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 378px;"><strong>Path</strong></th>
<th style="width: 78px;"><strong>Type</strong></th>
<th style="width: 284px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 378px;">Endpoint.ID</td>
<td style="width: 78px;">string</td>
<td style="width: 284px;">Endpoint ID.</td>
</tr>
<tr>
<td style="width: 378px;">Endpoint.MACAddress</td>
<td style="width: 78px;">string</td>
<td style="width: 284px;">Endpoint MAC address.</td>
</tr>
<tr>
<td style="width: 378px;">CiscoISE.Endpoint.ID</td>
<td style="width: 78px;">string</td>
<td style="width: 284px;">Endpoint ID.</td>
</tr>
<tr>
<td style="width: 378px;">CiscoISE.Endpoint.MACAddress</td>
<td style="width: 78px;">string</td>
<td style="width: 284px;">Endpoint MAC address.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!cisco-ise-get-endpoints</pre>
<h5>Context Example</h5>
<pre>{
    "CiscoISE.Endpoint": [
        {
            "MACAddress": "00:0A:35:11:A9:00", 
            "ID": "50080fc0-a07a-11e8-808e-000c295fdd32"
        }, 
        {
            "MACAddress": "00:0E:35:D4:D8:51", 
            "ID": "327b0120-4ba1-11e8-93bd-000c296ec148"
        }, 
        {
            "MACAddress": "11:22:33:AA:BB:CC", 
            "ID": "7d5e0530-133c-11e9-a5db-02420d3c5249"
        }
    ], 
    "Endpoint": [
        {
            "MACAddress": "00:0A:35:11:A9:00", 
            "ID": "50080fc0-a07a-11e8-808e-000c295fdd32"
        }, 
        {
            "MACAddress": "00:0E:35:D4:D8:51", 
            "ID": "327b0120-4ba1-11e8-93bd-000c296ec148"
        }, 
        {
            "MACAddress": "11:22:33:AA:BB:CC", 
            "ID": "7d5e0530-133c-11e9-a5db-02420d3c5249"
        }
    ]
}
</pre>
<h5>Human Readable Output</h5>
<h3>Cisco ISE Endpoints</h3>
<table border="2">
<thead>
<tr>
<th>ID</th>
<th>MACAddress</th>
</tr>
</thead>
<tbody>
<tr>
<td>50080fc0-a07a-11e8-808e-000c295fdd32</td>
<td>00:0A:35:11:A9:00</td>
</tr>
<tr>
<td>327b0120-4ba1-11e8-93bd-000c296ec148</td>
<td>00:0E:35:D4:D8:51</td>
</tr>
<tr>
<td>7d5e0530-133c-11e9-a5db-02420d3c5249</td>
<td>11:22:33:AA:BB:CC</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_b6845c4c-5eb7-4340-af4c-30e7c7349036">5. Update custom attributes of an endpoint</h3>
<hr>
<p>Updates the custom attributes of an endpoint.</p>
<h5>Base Command</h5>
<p><code>cisco-ise-update-endpoint-custom-attribute</code></p>
<h5>Input</h5>
<p> </p>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 170px;"><strong>Argument Name</strong></th>
<th style="width: 499px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 170px;">id</td>
<td style="width: 499px;">Endpoint ID.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 170px;">macAddress</td>
<td style="width: 499px;">MAC address of the endpoint (format 11:22:33:44:55:66).</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 170px;">attributeName</td>
<td style="width: 499px;">A CSV list of attributes, for example, "attributeName=firstAttribute,secondAttribute".</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 170px;">attributeValue</td>
<td style="width: 499px;">A CSV list of attribute values, for example, "attributeValue=firstValue,secondValue".</td>
<td style="width: 71px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<h5>Command Example</h5>
<pre>!cisco-ise-update-endpoint-custom-attribute macAddress=00:0E:35:D4:D8:51 attributeName=mytest attributeValue=test1=testing</pre>
<h5>Human Readable Output</h5>
<p>Successfully updated endpoint 327b0120-4ba1-11e8-93bd-000c296ec148, the new custom fields are: "{test1=testing}"</p>
<h3 id="h_873ab8be-3282-4573-a1cb-25ce224ee813">6. Update the group of an endpoint</h3>
<hr>
<p>Updates the group of an endpoint.</p>
<h5>Base Command</h5>
<p><code>cisco-ise-update-endpoint-group</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 158px;"><strong>Argument Name</strong></th>
<th style="width: 496px;"><strong>Description</strong></th>
<th style="width: 86px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 158px;">groupId</td>
<td style="width: 496px;">The group ID to assign to this endpoint, e.g. 1</td>
<td style="width: 86px;">Optional</td>
</tr>
<tr>
<td style="width: 158px;">macAddress</td>
<td style="width: 496px;">MAC address of the endpoint (format 11:22:33:44:55:66).</td>
<td style="width: 86px;">Optional</td>
</tr>
<tr>
<td style="width: 158px;">id</td>
<td style="width: 496px;">Endpoint ID of the endpoint to update.</td>
<td style="width: 86px;">Optional</td>
</tr>
<tr>
<td style="width: 158px;">groupName</td>
<td style="width: 496px;">Name of the group to update for the endpoint.</td>
<td style="width: 86px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<h5>Command Example</h5>
<pre>!cisco-ise-update-endpoint-group groupName=Blacklist id=7d5e0530-133c-11e9-a5db-02420d3c5249</pre>
<h5>Human Readable Output</h5>
<p>Endpoint 7d5e0530-133c-11e9-a5db-02420d3c5249 updated successfully</p>
<h3 id="h_df978421-5af4-47b9-933c-8bdb414c5176">7. Get a collection of endpoint identity groups</h3>
<hr>
<p>Retrieves a collection of endpoint identity groups.</p>
<h5>Base Command</h5>
<p><code>cisco-ise-get-groups</code></p>
<h5>Input</h5>
<p>There are no arguments for this command.</p>
<h5>Context Output</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 246px;"><strong>Path</strong></th>
<th style="width: 59px;"><strong>Type</strong></th>
<th style="width: 435px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 246px;">CiscoISE.Group.Description</td>
<td style="width: 59px;">String</td>
<td style="width: 435px;">The description of the endpoint identity groups.</td>
</tr>
<tr>
<td style="width: 246px;">CiscoISE.Group.ID</td>
<td style="width: 59px;">String</td>
<td style="width: 435px;">The ID of the endpoint identity groups.</td>
</tr>
<tr>
<td style="width: 246px;">CiscoISE.Group.Name</td>
<td style="width: 59px;">String</td>
<td style="width: 435px;">The name of the endpoint identity groups.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!cisco-ise-get-groups</pre>
<h5>Context Example</h5>
<pre>{
    "CiscoISE.Group": [
        {
            "Name": "Sony-Device", 
            "Description": "Identity Group for Profile: Sony-Device", 
            "ID": "38a73670-8c00-11e6-996c-525400b48521"
        }, 
        {
            "Name": "Cisco-Meraki-Device", 
            "Description": "Identity Group for Profile: Cisco-Meraki-Device", 
            "ID": "1e2700a0-8c00-11e6-996c-525400b48521"
        }, 
        {
            "Name": "Apple-iDevice", 
            "Description": "Identity Group for Profile: Apple-iDevice", 
            "ID": "0a4a50f0-8c00-11e6-996c-525400b48521"
        }, 
        {
            "Name": "BlackBerry", 
            "Description": "Identity Group for Profile: BlackBerry", 
            "ID": "0cc7ad00-8c00-11e6-996c-525400b48521"
        }, 
        {
            "Name": "Android", 
            "Description": "Identity Group for Profile: Android", 
            "ID": "ffa36b00-8bff-11e6-996c-525400b48521"
        }, 
        {
            "Name": "Axis-Device", 
            "Description": "Identity Group for Profile: Axis-Device", 
            "ID": "0c4eac70-8c00-11e6-996c-525400b48521"
        }, 
        {
            "Name": "Juniper-Device", 
            "Description": "Identity Group for Profile: Juniper-Device", 
            "ID": "2b07d100-8c00-11e6-996c-525400b48521"
        }, 
        {
            "Name": "Epson-Device", 
            "Description": "Identity Group for Profile: Epson-Device", 
            "ID": "22c6c780-8c00-11e6-996c-525400b48521"
        }, 
        {
            "Name": "Profiled", 
            "Description": "Profiled Identity Group", 
            "ID": "aa10ae00-8bff-11e6-996c-525400b48521"
        }, 
        {
            "Name": "Blacklist", 
            "Description": "Blacklist Identity Group", 
            "ID": "aa000c30-8bff-11e6-996c-525400b48521"
        }, 
        {
            "Name": "GuestEndpoints", 
            "Description": "Guest Endpoints Identity Group", 
            "ID": "aa178bd0-8bff-11e6-996c-525400b48521"
        }, 
        {
            "Name": "Synology-Device", 
            "Description": "Identity Group for Profile: Synology-Device", 
            "ID": "3a1b38d0-8c00-11e6-996c-525400b48521"
        }, 
        {
            "Name": "Vizio-Device", 
            "Description": "Identity Group for Profile: Vizio-Device", 
            "ID": "3b113190-8c00-11e6-996c-525400b48521"
        }, 
        {
            "Name": "Trendnet-Device", 
            "Description": "Identity Group for Profile: Trendnet-Device", 
            "ID": "3a88eec0-8c00-11e6-996c-525400b48521"
        }, 
        {
            "Name": "RegisteredDevices", 
            "Description": "Asset Registered Endpoints Identity Group", 
            "ID": "aa13bb40-8bff-11e6-996c-525400b48521"
        }, 
        {
            "Name": "Cisco-IP-Phone", 
            "Description": "Identity Group for Profile: Cisco-IP-Phone", 
            "ID": "14f5cac0-8c00-11e6-996c-525400b48521"
        }, 
        {
            "Name": "Unknown", 
            "Description": "Unknown Identity Group", 
            "ID": "aa0e8b20-8bff-11e6-996c-525400b48521"
        }, 
        {
            "Name": "Workstation", 
            "Description": "Identity Group for Profile: Workstation", 
            "ID": "3b76f840-8c00-11e6-996c-525400b48521"
        }
    ]
}
</pre>
<h5>Human Readable Output</h5>
<h3>Cisco pxGrid ISE Groups</h3>
<table border="2">
<thead>
<tr>
<th>ID</th>
<th>Name</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>38a73670-8c00-11e6-996c-525400b48521</td>
<td>Sony-Device</td>
<td>Identity Group for Profile: Sony-Device</td>
</tr>
<tr>
<td>1e2700a0-8c00-11e6-996c-525400b48521</td>
<td>Cisco-Meraki-Device</td>
<td>Identity Group for Profile: Cisco-Meraki-Device</td>
</tr>
<tr>
<td>0a4a50f0-8c00-11e6-996c-525400b48521</td>
<td>Apple-iDevice</td>
<td>Identity Group for Profile: Apple-iDevice</td>
</tr>
<tr>
<td>0cc7ad00-8c00-11e6-996c-525400b48521</td>
<td>BlackBerry</td>
<td>Identity Group for Profile: BlackBerry</td>
</tr>
<tr>
<td>ffa36b00-8bff-11e6-996c-525400b48521</td>
<td>Android</td>
<td>Identity Group for Profile: Android</td>
</tr>
<tr>
<td>0c4eac70-8c00-11e6-996c-525400b48521</td>
<td>Axis-Device</td>
<td>Identity Group for Profile: Axis-Device</td>
</tr>
<tr>
<td>2b07d100-8c00-11e6-996c-525400b48521</td>
<td>Juniper-Device</td>
<td>Identity Group for Profile: Juniper-Device</td>
</tr>
<tr>
<td>22c6c780-8c00-11e6-996c-525400b48521</td>
<td>Epson-Device</td>
<td>Identity Group for Profile: Epson-Device</td>
</tr>
<tr>
<td>aa10ae00-8bff-11e6-996c-525400b48521</td>
<td>Profiled</td>
<td>Profiled Identity Group</td>
</tr>
<tr>
<td>aa000c30-8bff-11e6-996c-525400b48521</td>
<td>Blacklist</td>
<td>Blacklist Identity Group</td>
</tr>
<tr>
<td>aa178bd0-8bff-11e6-996c-525400b48521</td>
<td>GuestEndpoints</td>
<td>Guest Endpoints Identity Group</td>
</tr>
<tr>
<td>3a1b38d0-8c00-11e6-996c-525400b48521</td>
<td>Synology-Device</td>
<td>Identity Group for Profile: Synology-Device</td>
</tr>
<tr>
<td>3b113190-8c00-11e6-996c-525400b48521</td>
<td>Vizio-Device</td>
<td>Identity Group for Profile: Vizio-Device</td>
</tr>
<tr>
<td>3a88eec0-8c00-11e6-996c-525400b48521</td>
<td>Trendnet-Device</td>
<td>Identity Group for Profile: Trendnet-Device</td>
</tr>
<tr>
<td>aa13bb40-8bff-11e6-996c-525400b48521</td>
<td>RegisteredDevices</td>
<td>Asset Registered Endpoints Identity Group</td>
</tr>
<tr>
<td>14f5cac0-8c00-11e6-996c-525400b48521</td>
<td>Cisco-IP-Phone</td>
<td>Identity Group for Profile: Cisco-IP-Phone</td>
</tr>
<tr>
<td>aa0e8b20-8bff-11e6-996c-525400b48521</td>
<td>Unknown</td>
<td>Unknown Identity Group</td>
</tr>
<tr>
<td>3b76f840-8c00-11e6-996c-525400b48521</td>
<td>Workstation</td>
<td>Identity Group for Profile: Workstation</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_636ec1ff-018e-45b1-8ac1-1fdd1c43cbaa">8. Get all ANC policies</h3>
<hr>
<p>Returns all Adaptive Network Control policies.</p>
<h5>Base Command</h5>
<p><code>cisco-ise-get-policies</code></p>
<h5>Input</h5>
<p>There are no arguments for this command.</p>
<h5>Context Output</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 299px;"><strong>Path</strong></th>
<th style="width: 66px;"><strong>Type</strong></th>
<th style="width: 375px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 299px;">CiscoISE.Policy.Description</td>
<td style="width: 66px;">String</td>
<td style="width: 375px;">The description of the ANC policy.</td>
</tr>
<tr>
<td style="width: 299px;">CiscoISE.Policy.ID</td>
<td style="width: 66px;">String</td>
<td style="width: 375px;">The ID of the ANC policy.</td>
</tr>
<tr>
<td style="width: 299px;">CiscoISE.Policy.Name</td>
<td style="width: 66px;">String</td>
<td style="width: 375px;">The name of the ANC policy.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!cisco-ise-get-policies</pre>
<h5>Context Example</h5>
<pre>{
    "CiscoISE.Policy": [
        {
            "ID": "ANCPortBounce", 
            "Name": "ANCPortBounce"
        }, 
        {
            "ID": "ANCQuarantine", 
            "Name": "ANCQuarantine"
        }, 
        {
            "ID": "ANCShutdown", 
            "Name": "ANCShutdown"
        }, 
        {
            "ID": "azoce", 
            "Name": "azoce"
        }, 
        {
            "ID": "dpkef", 
            "Name": "dpkef"
        }, 
        {
            "ID": "dvgoy", 
            "Name": "dvgoy"
        }, 
        {
            "ID": "gfibg", 
            "Name": "gfibg"
        }, 
        {
            "ID": "jzbhh", 
            "Name": "jzbhh"
        }, 
        {
            "ID": "last-test", 
            "Name": "last-test"
        }, 
        {
            "ID": "ljnba", 
            "Name": "ljnba"
        }, 
        {
            "ID": "mhxab", 
            "Name": "mhxab"
        }, 
        {
            "ID": "mxiiw", 
            "Name": "mxiiw"
        }, 
        {
            "ID": "ncxer", 
            "Name": "ncxer"
        }, 
        {
            "ID": "phzbe", 
            "Name": "phzbe"
        }, 
        {
            "ID": "pjrgp", 
            "Name": "pjrgp"
        }, 
        {
            "ID": "policy0", 
            "Name": "policy0"
        }, 
        {
            "ID": "policy09", 
            "Name": "policy09"
        }, 
        {
            "ID": "policy1", 
            "Name": "policy1"
        }, 
        {
            "ID": "policy2", 
            "Name": "policy2"
        }, 
        {
            "ID": "policy3", 
            "Name": "policy3"
        }
    ]
}
</pre>
<h5>Human Readable Output</h5>
<h3>CiscoISE Adaptive Network Control Policies</h3>
<table border="2">
<thead>
<tr>
<th>ID</th>
<th>Name</th>
</tr>
</thead>
<tbody>
<tr>
<td>ANCPortBounce</td>
<td>ANCPortBounce</td>
</tr>
<tr>
<td>ANCQuarantine</td>
<td>ANCQuarantine</td>
</tr>
<tr>
<td>ANCShutdown</td>
<td>ANCShutdown</td>
</tr>
<tr>
<td>azoce</td>
<td>azoce</td>
</tr>
<tr>
<td>dpkef</td>
<td>dpkef</td>
</tr>
<tr>
<td>dvgoy</td>
<td>dvgoy</td>
</tr>
<tr>
<td>gfibg</td>
<td>gfibg</td>
</tr>
<tr>
<td>jzbhh</td>
<td>jzbhh</td>
</tr>
<tr>
<td>last-test</td>
<td>last-test</td>
</tr>
<tr>
<td>ljnba</td>
<td>ljnba</td>
</tr>
<tr>
<td>mhxab</td>
<td>mhxab</td>
</tr>
<tr>
<td>mxiiw</td>
<td>mxiiw</td>
</tr>
<tr>
<td>ncxer</td>
<td>ncxer</td>
</tr>
<tr>
<td>phzbe</td>
<td>phzbe</td>
</tr>
<tr>
<td>pjrgp</td>
<td>pjrgp</td>
</tr>
<tr>
<td>policy0</td>
<td>policy0</td>
</tr>
<tr>
<td>policy09</td>
<td>policy09</td>
</tr>
<tr>
<td>policy1</td>
<td>policy1</td>
</tr>
<tr>
<td>policy2</td>
<td>policy2</td>
</tr>
<tr>
<td>policy3</td>
<td>policy3</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_4be7bcf4-cba4-4762-beae-54a901e2eedd">9. Get a single ANC policy</h3>
<hr>
<p>Returns a single Adaptive Network Control policy.</p>
<h5>Base Command</h5>
<p><code>cisco-ise-get-policy</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 198px;"><strong>Argument Name</strong></th>
<th style="width: 428px;"><strong>Description</strong></th>
<th style="width: 114px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 198px;">policy_name</td>
<td style="width: 428px;">The name of the ANC policy to return.</td>
<td style="width: 114px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<p> </p>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 154px;"><strong>Path</strong></th>
<th style="width: 58px;"><strong>Type</strong></th>
<th style="width: 528px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 154px;">CiscoISE.Policy.Action</td>
<td style="width: 58px;">String</td>
<td style="width: 528px;">The action of the policy. Can be "QUARANTINE", "PORTBOUNCE", or "SHUTDOWN".</td>
</tr>
<tr>
<td style="width: 154px;">CiscoISE.Policy.ID</td>
<td style="width: 58px;">String</td>
<td style="width: 528px;">The ID of the ANC policy.</td>
</tr>
<tr>
<td style="width: 154px;">CiscoISE.Policy.Link</td>
<td style="width: 58px;">String</td>
<td style="width: 528px;">The link for the ANC policy (GUI).</td>
</tr>
<tr>
<td style="width: 154px;">CiscoISE.Policy.Name</td>
<td style="width: 58px;">String</td>
<td style="width: 528px;">The name of the ANC policy.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!cisco-ise-get-policy policy_name=policy3</pre>
<h5>Context Example</h5>
<pre>{
    "CiscoISE.Policy": [
        {
            "Action": [
                "QUARANTINE"
            ], 
            "Name": "policy3"
        }
    ]
}
</pre>
<h5>Human Readable Output</h5>
<h3>CiscoISE Policy</h3>
<table border="2">
<thead>
<tr>
<th>Action</th>
<th>Name</th>
</tr>
</thead>
<tbody>
<tr>
<td>QUARANTINE</td>
<td>policy3</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_a62bd46e-8b18-4f75-9215-2c1305374a47">10. Create an ANC policy</h3>
<hr>
<p>Creates an ANC policy.</p>
<h5>Base Command</h5>
<p><code>cisco-ise-create-policy</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 144px;"><strong>Argument Name</strong></th>
<th style="width: 525px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 144px;">policy_actions</td>
<td style="width: 525px;">The actions of the policy. Can be "QUARANTINE", "PORTBOUNCE", or "SHUTDOWN".</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 144px;">policy_name</td>
<td style="width: 525px;">The name of the new adaptive network control policy.</td>
<td style="width: 71px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 270px;"><strong>Path</strong></th>
<th style="width: 69px;"><strong>Type</strong></th>
<th style="width: 401px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 270px;">CiscoISE.Policy.Action</td>
<td style="width: 69px;">String</td>
<td style="width: 401px;">The actions of the ANC policy.</td>
</tr>
<tr>
<td style="width: 270px;">CiscoISE.Policy.Name</td>
<td style="width: 69px;">String</td>
<td style="width: 401px;">The name of the new ANC policy.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!cisco-ise-create-policy policy_name=quarantinePolicy policy_actions=QUARANTINE</pre>
<h5>Context Example</h5>
<pre>{
    "CiscoISE.Policy": {
        "Action": [
            "QUARANTINE"
        ], 
        "Name": "quarantinePolicy"
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>The policy "quarantinePolicy" has been created successfully</p>
<h3 id="h_19abc45f-7827-416c-bbc4-2f2be27c6453">11. Assign an ANC policy to an endpoint</h3>
<hr>
<p>Assigns an Adapative Network Control policy to an endpoint.</p>
<h5>Base Command</h5>
<p><code>cisco-ise-assign-policy</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 170px;"><strong>Argument Name</strong></th>
<th style="width: 473px;"><strong>Description</strong></th>
<th style="width: 97px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 170px;">mac_address</td>
<td style="width: 473px;">The MAC address to which to apply the policy.</td>
<td style="width: 97px;">Required</td>
</tr>
<tr>
<td style="width: 170px;">policy_name</td>
<td style="width: 473px;">The name of the policy to assign to the endpoint.</td>
<td style="width: 97px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 258px;"><strong>Path</strong></th>
<th style="width: 57px;"><strong>Type</strong></th>
<th style="width: 425px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 258px;">CiscoISE.Endpoint.MACAddress</td>
<td style="width: 57px;">String</td>
<td style="width: 425px;">The MAC address of the endpoint.</td>
</tr>
<tr>
<td style="width: 258px;">CiscoISE.Endpoint.PolicyName</td>
<td style="width: 57px;">String</td>
<td style="width: 425px;">The policy name that was applied to the endpoint.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!cisco-ise-assign-policy mac_address=50080fc0-a07a-11e8-808e-000c295fdd32 policy_name=policy3</pre>
<h5>Human Readable Output</h5>
<h3>The policy "policy3" has been applied successfully</h3>
<h3 id="h_f60063f9-8c7f-4198-945e-829c34c16fcb">12. Get all endpoints on block list.</h3>
<hr>
<p>Returns all blacklisted endpoints.</p>
<h5>Base Command</h5>
<p><code>cisco-ise-get-blacklist-endpoints</code></p>
<h5>Input</h5>
<p>There are no arguments for this command.</p>
<h5>Context Output</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 362px;"><strong>Path</strong></th>
<th style="width: 65px;"><strong>Type</strong></th>
<th style="width: 313px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 362px;">CiscoISE.Endpoint.ID</td>
<td style="width: 65px;">String</td>
<td style="width: 313px;">The endpoint ID.</td>
</tr>
<tr>
<td style="width: 362px;">CiscoISE.Endpoint.Name</td>
<td style="width: 65px;">String</td>
<td style="width: 313px;">The name of the endpoint.</td>
</tr>
<tr>
<td style="width: 362px;">CiscoISE.Endpoint.Description</td>
<td style="width: 65px;">String</td>
<td style="width: 313px;">The endpoint description.</td>
</tr>
<tr>
<td style="width: 362px;">CiscoISE.Endpoint.Link</td>
<td style="width: 65px;">String</td>
<td style="width: 313px;">The link for the endpoint</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!cisco-ise-get-blacklist-endpoints</pre>
<h5>Context Example</h5>
<pre>{
    "CiscoISE.Endpoint": [
        {
            "GroupName": "Blacklist", 
            "ID": "327b0120-4ba1-11e8-93bd-000c296ec148", 
            "Name": "00:0E:35:D4:D8:51"
        }
    ]
}
</pre>
<h5>Human Readable Output</h5>
<h3>CiscoISE Blacklist Endpoints</h3>
<table border="2">
<thead>
<tr>
<th>GroupName</th>
<th>ID</th>
<th>Name</th>
</tr>
</thead>
<tbody>
<tr>
<td>Blacklist</td>
<td>327b0120-4ba1-11e8-93bd-000c296ec148</td>
<td>00:0E:35:D4:D8:51</td>
</tr>
</tbody>
</table>